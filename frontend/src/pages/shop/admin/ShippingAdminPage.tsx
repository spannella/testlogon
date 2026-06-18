/**
 * ShippingAdminPage (SHP-016 / SHP-017)
 *
 * Admin UI for the Shipping Logistics module.
 * Route: /shop/admin/shipping
 *
 * Tabs:
 *   Carriers      — list + toggle carriers, add new carrier, view per-carrier methods
 *   Rate Estimate — enter destination & weight, preview available rate options
 *   Shipments     — search by order id, view status, advance shipment state
 */

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Loader2,
  Truck,
  DollarSign,
  Package,
  Plus,
  ChevronRight,
  AlertTriangle,
  RefreshCw,
} from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Switch } from "@/components/ui/switch";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { EmptyState } from "@/components/shared/EmptyState";

import {
  listCarriers,
  createCarrier,
  updateCarrier,
  listMethods,
  estimateRates,
  listOrderShipments,
  advanceShipment,
  type CarrierCode,
  type MethodCode,
  type ShipmentStatus,
} from "@/api/endpoints/shipping";

// ─── helpers ─────────────────────────────────────────────────────────────────

const CARRIER_CODES: CarrierCode[] = ["ups", "fedex", "usps", "dhl", "manual"];

const STATUS_COLORS: Record<string, string> = {
  pending_fulfillment: "bg-slate-100 text-slate-700",
  label_created: "bg-blue-100 text-blue-700",
  picked_up: "bg-indigo-100 text-indigo-700",
  in_transit: "bg-amber-100 text-amber-700",
  out_for_delivery: "bg-orange-100 text-orange-700",
  delivered: "bg-emerald-100 text-emerald-700",
  exception: "bg-red-100 text-red-700",
  returned: "bg-purple-100 text-purple-700",
  cancelled: "bg-gray-100 text-gray-500",
};

function StatusBadge({ status }: { status: string }) {
  const cls = STATUS_COLORS[status] ?? "bg-gray-100 text-gray-500";
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${cls}`}
    >
      {status.replace(/_/g, " ")}
    </span>
  );
}

function fmtCents(cents: number) {
  return `$${(cents / 100).toFixed(2)}`;
}

// ─── Carriers tab ─────────────────────────────────────────────────────────────

function CarriersTab() {
  const qc = useQueryClient();

  const [showAdd, setShowAdd] = useState(false);
  const [newDisplayName, setNewDisplayName] = useState("");
  const [newCode, setNewCode] = useState<CarrierCode>("manual");
  const [newTracking, setNewTracking] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const carriersQuery = useQuery({
    queryKey: ["shipping", "carriers", "all"],
    queryFn: () => listCarriers(false), // include disabled
  });

  const methodsQuery = useQuery({
    queryKey: ["shipping", "methods", expandedId],
    queryFn: () => listMethods(expandedId!, false),
    enabled: !!expandedId,
  });

  const createMut = useMutation({
    mutationFn: () =>
      createCarrier({ carrier_code: newCode, display_name: newDisplayName }),
    onSuccess: () => {
      toast.success("Carrier created");
      setShowAdd(false);
      setNewDisplayName("");
      setNewCode("manual");
      setNewTracking(false);
      qc.invalidateQueries({ queryKey: ["shipping", "carriers"] });
    },
    onError: () => toast.error("Failed to create carrier"),
  });

  const toggleMut = useMutation({
    mutationFn: ({
      carrierId,
      enabled,
    }: {
      carrierId: string;
      enabled: boolean;
    }) => updateCarrier(carrierId, { enabled }),
    onSuccess: () => {
      toast.success("Carrier updated");
      qc.invalidateQueries({ queryKey: ["shipping", "carriers"] });
    },
    onError: () => toast.error("Failed to update carrier"),
  });

  const carriers = carriersQuery.data ?? [];

  return (
    <div className="space-y-4">
      {/* Header row */}
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          Manage shipping carriers and their methods.
        </p>
        <Button size="sm" onClick={() => setShowAdd((v) => !v)}>
          <Plus className="mr-1 h-4 w-4" />
          Add carrier
        </Button>
      </div>

      {/* Add carrier form */}
      {showAdd && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">New carrier</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <div>
                <Label htmlFor="carrier-name">Display name</Label>
                <Input
                  id="carrier-name"
                  value={newDisplayName}
                  onChange={(e) => setNewDisplayName(e.target.value)}
                  placeholder="e.g. FedEx Ground"
                />
              </div>
              <div>
                <Label htmlFor="carrier-code">Carrier code</Label>
                <Select
                  value={newCode}
                  onValueChange={(v) => setNewCode(v as CarrierCode)}
                >
                  <SelectTrigger id="carrier-code">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {CARRIER_CODES.map((c) => (
                      <SelectItem key={c} value={c}>
                        {c}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="flex flex-col justify-end">
                <div className="flex items-center gap-2 pb-1">
                  <Checkbox
                    id="online-tracking"
                    checked={newTracking}
                    onCheckedChange={(v) => setNewTracking(!!v)}
                  />
                  <Label htmlFor="online-tracking">Online tracking</Label>
                </div>
              </div>
            </div>
            <div className="flex gap-2">
              <Button
                size="sm"
                disabled={!newDisplayName.trim() || createMut.isPending}
                onClick={() => createMut.mutate()}
              >
                {createMut.isPending && (
                  <Loader2 className="mr-1 h-4 w-4 animate-spin" />
                )}
                Save
              </Button>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => setShowAdd(false)}
              >
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Carriers list */}
      {carriersQuery.isLoading ? (
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" /> Loading carriers…
        </div>
      ) : carriers.length === 0 ? (
        <EmptyState
          icon={<Truck className="h-10 w-10" />}
          title="No carriers configured"
          description="Add a carrier above to get started."
        />
      ) : (
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Display name</TableHead>
                <TableHead>Code</TableHead>
                <TableHead>Online tracking</TableHead>
                <TableHead>Enabled</TableHead>
                <TableHead>Methods</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {carriers.map((c) => (
                <>
                  <TableRow key={c.carrier_id}>
                    <TableCell className="font-medium">
                      {c.display_name}
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-xs">{c.carrier_code}</span>
                    </TableCell>
                    <TableCell>
                      {c.online_tracking ? (
                        <Badge
                          variant="outline"
                          className="border-emerald-500 text-emerald-600"
                        >
                          Yes
                        </Badge>
                      ) : (
                        <Badge
                          variant="outline"
                          className="text-muted-foreground"
                        >
                          No
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell>
                      <Switch
                        checked={c.enabled}
                        disabled={toggleMut.isPending}
                        onCheckedChange={(checked) =>
                          toggleMut.mutate({
                            carrierId: c.carrier_id,
                            enabled: checked,
                          })
                        }
                      />
                    </TableCell>
                    <TableCell>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() =>
                          setExpandedId((prev) =>
                            prev === c.carrier_id ? null : c.carrier_id,
                          )
                        }
                      >
                        <ChevronRight
                          className={`h-4 w-4 transition-transform ${
                            expandedId === c.carrier_id ? "rotate-90" : ""
                          }`}
                        />
                        {expandedId === c.carrier_id ? "Hide" : "View"}
                      </Button>
                    </TableCell>
                  </TableRow>

                  {/* Methods sub-table */}
                  {expandedId === c.carrier_id && (
                    <TableRow key={`${c.carrier_id}-methods`}>
                      <TableCell colSpan={5} className="bg-muted/30 p-0">
                        <div className="px-6 py-3">
                          {methodsQuery.isLoading ? (
                            <div className="flex items-center gap-2 text-sm text-muted-foreground">
                              <Loader2 className="h-4 w-4 animate-spin" />{" "}
                              Loading methods…
                            </div>
                          ) : (methodsQuery.data ?? []).length === 0 ? (
                            <p className="text-sm text-muted-foreground">
                              No methods configured for this carrier.
                            </p>
                          ) : (
                            <Table>
                              <TableHeader>
                                <TableRow>
                                  <TableHead>Method</TableHead>
                                  <TableHead>Label</TableHead>
                                  <TableHead>Base rate</TableHead>
                                  <TableHead>Transit (days)</TableHead>
                                  <TableHead>Enabled</TableHead>
                                </TableRow>
                              </TableHeader>
                              <TableBody>
                                {(methodsQuery.data ?? []).map((m) => (
                                  <TableRow key={m.method_code}>
                                    <TableCell className="font-mono text-xs">
                                      {m.method_code}
                                    </TableCell>
                                    <TableCell>{m.method_label}</TableCell>
                                    <TableCell>
                                      {fmtCents(m.base_rate_cents)}
                                    </TableCell>
                                    <TableCell>
                                      {m.transit_days_min != null &&
                                      m.transit_days_max != null
                                        ? `${m.transit_days_min}–${m.transit_days_max}`
                                        : (m.transit_days_min ??
                                          m.transit_days_max ??
                                          "—")}
                                    </TableCell>
                                    <TableCell>
                                      {m.enabled ? (
                                        <Badge
                                          variant="outline"
                                          className="border-emerald-500 text-emerald-600"
                                        >
                                          Yes
                                        </Badge>
                                      ) : (
                                        <Badge
                                          variant="outline"
                                          className="text-muted-foreground"
                                        >
                                          No
                                        </Badge>
                                      )}
                                    </TableCell>
                                  </TableRow>
                                ))}
                              </TableBody>
                            </Table>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  )}
                </>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}

// ─── Rate Estimate tab ────────────────────────────────────────────────────────

const METHOD_CODES: MethodCode[] = [
  "ground",
  "express",
  "overnight",
  "economy",
  "flat_rate",
];

function RateEstimateTab() {
  const [carrierCode, setCarrierCode] = useState<CarrierCode>("usps");
  const [methodCode, setMethodCode] = useState<MethodCode>("ground");
  const [weightOz, setWeightOz] = useState("16");
  const [destZip, setDestZip] = useState("");

  const estimateQuery = useQuery({
    queryKey: [
      "shipping",
      "estimate",
      carrierCode,
      methodCode,
      weightOz,
      destZip,
    ],
    queryFn: () =>
      estimateRates({
        carrier_code: carrierCode,
        method_code: methodCode,
        weight_oz: Number(weightOz),
        destination_zip: destZip,
      }),
    enabled: false, // only runs on explicit user action
  });

  const options = estimateQuery.data?.options ?? [];

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Preview shipping costs for a carrier + method + destination combination.
      </p>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Rate parameters</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <div>
              <Label>Carrier</Label>
              <Select
                value={carrierCode}
                onValueChange={(v) => setCarrierCode(v as CarrierCode)}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CARRIER_CODES.map((c) => (
                    <SelectItem key={c} value={c}>
                      {c}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>Method</Label>
              <Select
                value={methodCode}
                onValueChange={(v) => setMethodCode(v as MethodCode)}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {METHOD_CODES.map((m) => (
                    <SelectItem key={m} value={m}>
                      {m}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label htmlFor="weight-oz">Weight (oz)</Label>
              <Input
                id="weight-oz"
                type="number"
                min={0.1}
                step={0.1}
                value={weightOz}
                onChange={(e) => setWeightOz(e.target.value)}
              />
            </div>
            <div>
              <Label htmlFor="dest-zip">Destination zip</Label>
              <Input
                id="dest-zip"
                value={destZip}
                onChange={(e) => setDestZip(e.target.value)}
                placeholder="e.g. 90210"
                onKeyDown={(e) => {
                  if (e.key === "Enter" && destZip.trim())
                    estimateQuery.refetch();
                }}
              />
            </div>
          </div>
          <Button
            size="sm"
            disabled={!destZip.trim() || estimateQuery.isFetching}
            onClick={() => estimateQuery.refetch()}
          >
            {estimateQuery.isFetching ? (
              <Loader2 className="mr-1 h-4 w-4 animate-spin" />
            ) : (
              <DollarSign className="mr-1 h-4 w-4" />
            )}
            Get estimate
          </Button>
        </CardContent>
      </Card>

      {estimateQuery.isError && (
        <div className="flex items-center gap-2 rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          Failed to fetch rate estimate. Check that the carrier and method are
          configured.
        </div>
      )}

      {estimateQuery.isSuccess && options.length === 0 && (
        <EmptyState
          icon={<DollarSign className="h-10 w-10" />}
          title="No rate options returned"
          description="The carrier/method may not have a base rate configured."
        />
      )}

      {options.length > 0 && (
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Carrier</TableHead>
                <TableHead>Method</TableHead>
                <TableHead>Rate</TableHead>
                <TableHead>Currency</TableHead>
                <TableHead>Transit (days)</TableHead>
                <TableHead>Est. delivery</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {options.map((opt, i) => (
                <TableRow key={i}>
                  <TableCell className="font-mono text-xs">
                    {opt.carrier_code}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {opt.method_code}
                  </TableCell>
                  <TableCell className="tabular-nums font-semibold">
                    {fmtCents(opt.rate_cents)}
                  </TableCell>
                  <TableCell>{opt.currency}</TableCell>
                  <TableCell>
                    {opt.transit_days_min != null && opt.transit_days_max != null
                      ? `${opt.transit_days_min}–${opt.transit_days_max}`
                      : (opt.transit_days_min ?? opt.transit_days_max ?? "—")}
                  </TableCell>
                  <TableCell>{opt.estimated_delivery ?? "—"}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}

// ─── Shipments tab ────────────────────────────────────────────────────────────

const ADVANCE_TARGETS: ShipmentStatus[] = [
  "label_created",
  "picked_up",
  "in_transit",
  "out_for_delivery",
  "delivered",
  "exception",
  "returned",
  "cancelled",
];

function ShipmentsTab() {
  const qc = useQueryClient();

  const [orderId, setOrderId] = useState("");
  const [searchedOrderId, setSearchedOrderId] = useState<string | null>(null);
  const [advanceTarget, setAdvanceTarget] = useState<
    Record<string, ShipmentStatus>
  >({});
  const [advanceReason, setAdvanceReason] = useState<Record<string, string>>(
    {},
  );

  const shipmentsQuery = useQuery({
    queryKey: ["shipping", "order-shipments", searchedOrderId],
    queryFn: () => listOrderShipments(searchedOrderId!),
    enabled: !!searchedOrderId,
    retry: false,
  });

  const advanceMut = useMutation({
    mutationFn: ({
      shipmentId,
      target,
      reason,
    }: {
      shipmentId: string;
      target: ShipmentStatus;
      reason?: string;
    }) =>
      advanceShipment(shipmentId, {
        target_status: target,
        reason: reason || undefined,
      }),
    onSuccess: (updated) => {
      toast.success(
        `Shipment advanced to "${updated.status.replace(/_/g, " ")}"`,
      );
      qc.invalidateQueries({
        queryKey: ["shipping", "order-shipments", searchedOrderId],
      });
    },
    onError: () => toast.error("Failed to advance shipment"),
  });

  const shipments = shipmentsQuery.data?.shipments ?? [];

  return (
    <div className="space-y-4">
      {/* Search bar */}
      <div className="flex items-end gap-2">
        <div className="flex-1">
          <Label htmlFor="order-search">Order ID</Label>
          <Input
            id="order-search"
            value={orderId}
            onChange={(e) => setOrderId(e.target.value)}
            placeholder="Enter order id to search shipments"
            onKeyDown={(e) => {
              if (e.key === "Enter" && orderId.trim())
                setSearchedOrderId(orderId.trim());
            }}
          />
        </div>
        <Button
          disabled={!orderId.trim() || shipmentsQuery.isFetching}
          onClick={() => setSearchedOrderId(orderId.trim())}
        >
          {shipmentsQuery.isFetching ? (
            <Loader2 className="mr-1 h-4 w-4 animate-spin" />
          ) : (
            <RefreshCw className="mr-1 h-4 w-4" />
          )}
          Search
        </Button>
      </div>

      {!searchedOrderId && (
        <EmptyState
          icon={<Package className="h-10 w-10" />}
          title="Enter an order ID to view shipments"
          description="Shipments are scoped to a single order."
        />
      )}

      {shipmentsQuery.isError && (
        <div className="flex items-center gap-2 rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          Order not found or no shipments for that order ID.
        </div>
      )}

      {shipmentsQuery.isSuccess && shipments.length === 0 && (
        <EmptyState
          icon={<Package className="h-10 w-10" />}
          title="No shipments for this order"
          description="Create a shipment from the order lifecycle page."
        />
      )}

      {shipments.length > 0 && (
        <div className="space-y-3">
          {shipments.map((s) => (
            <Card key={s.shipment_id}>
              <CardContent className="pt-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  {/* Info */}
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs text-muted-foreground">
                        {s.shipment_id}
                      </span>
                      <StatusBadge status={s.status} />
                    </div>
                    <div className="text-sm">
                      <span className="font-medium">{s.carrier_code}</span>{" "}
                      <span className="text-muted-foreground">/</span>{" "}
                      {s.method_code}
                    </div>
                    {s.tracking_number && (
                      <div className="font-mono text-xs text-muted-foreground">
                        Tracking: {s.tracking_number}
                      </div>
                    )}
                    <div className="text-xs text-muted-foreground">
                      Created:{" "}
                      {new Date(s.created_at * 1000).toLocaleString()}
                    </div>
                  </div>

                  {/* Advance controls */}
                  <div className="flex flex-wrap items-end gap-2">
                    <div>
                      <Label className="text-xs">Advance to</Label>
                      <Select
                        value={advanceTarget[s.shipment_id] ?? ""}
                        onValueChange={(v) =>
                          setAdvanceTarget((prev) => ({
                            ...prev,
                            [s.shipment_id]: v as ShipmentStatus,
                          }))
                        }
                      >
                        <SelectTrigger className="h-8 w-44">
                          <SelectValue placeholder="Select status…" />
                        </SelectTrigger>
                        <SelectContent>
                          {ADVANCE_TARGETS.map((t) => (
                            <SelectItem key={t} value={t}>
                              {t.replace(/_/g, " ")}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div>
                      <Label className="text-xs">Reason (optional)</Label>
                      <Input
                        value={advanceReason[s.shipment_id] ?? ""}
                        onChange={(e) =>
                          setAdvanceReason((prev) => ({
                            ...prev,
                            [s.shipment_id]: e.target.value,
                          }))
                        }
                        placeholder="e.g. manual update"
                        className="h-8 w-44"
                      />
                    </div>
                    <Button
                      size="sm"
                      disabled={
                        !advanceTarget[s.shipment_id] || advanceMut.isPending
                      }
                      onClick={() =>
                        advanceMut.mutate({
                          shipmentId: s.shipment_id,
                          target: advanceTarget[s.shipment_id],
                          reason: advanceReason[s.shipment_id],
                        })
                      }
                    >
                      {advanceMut.isPending ? (
                        <Loader2 className="mr-1 h-4 w-4 animate-spin" />
                      ) : (
                        <Truck className="mr-1 h-4 w-4" />
                      )}
                      Advance
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Page root ────────────────────────────────────────────────────────────────

export function ShippingAdminPage() {
  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Truck className="h-6 w-6" />
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">
            Shipping Administration
          </h1>
          <p className="text-sm text-muted-foreground">
            Manage carriers, estimate rates, and track shipments.
          </p>
        </div>
      </div>

      <Tabs defaultValue="carriers">
        <TabsList>
          <TabsTrigger value="carriers">Carriers</TabsTrigger>
          <TabsTrigger value="estimate">Rate Estimate</TabsTrigger>
          <TabsTrigger value="shipments">Shipments</TabsTrigger>
        </TabsList>

        <TabsContent value="carriers" className="mt-4">
          <CarriersTab />
        </TabsContent>

        <TabsContent value="estimate" className="mt-4">
          <RateEstimateTab />
        </TabsContent>

        <TabsContent value="shipments" className="mt-4">
          <ShipmentsTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}

export default ShippingAdminPage;
